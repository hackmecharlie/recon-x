# ============================================================
# RECON-X | modules/web/screenshot.py
# Description: Async headless browser screenshots via Playwright
#              for both HTTP and HTTPS targets
# ============================================================

import asyncio
import logging
import re
from pathlib import Path
from typing import List, Optional

from engine.findings import ScreenshotResult

logger = logging.getLogger(__name__)

_SAFE_FILENAME_RE = re.compile(r"[^\w\-.]")


def _safe_filename(host: str, scheme: str) -> str:
    """Generate a safe filename for a screenshot.

    Args:
        host: Target hostname or IP.
        scheme: URL scheme (http/https).

    Returns:
        Safe filename string.
    """
    safe_host = _SAFE_FILENAME_RE.sub("_", host)
    return f"{safe_host}_{scheme}.png"


class ScreenshotCapture:
    """Capture web screenshots using Playwright headless Chromium.

    Navigates to each scheme (http/https) for the target host,
    waits for network idle, and saves a full-page PNG screenshot.
    """

    def __init__(
        self,
        host: str,
        schemes: List[str],
        output_dir: str,
        viewport_width: int = 1280,
        viewport_height: int = 800,
        page_timeout: int = 15000,
        full_page: bool = True,
    ) -> None:
        """Initialize ScreenshotCapture.

        Args:
            host: Target hostname or IP.
            schemes: List of URL schemes to try (e.g., ['http', 'https']).
            output_dir: Base output directory for saving screenshots.
            viewport_width: Browser viewport width in pixels.
            viewport_height: Browser viewport height in pixels.
            page_timeout: Page load timeout in milliseconds.
            full_page: Capture full-page screenshot (scroll to bottom).
        """
        self.host = host
        self.schemes = schemes
        self.output_dir = output_dir
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.page_timeout = page_timeout
        self.full_page = full_page
        self.screenshots_dir = Path(output_dir) / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)

    async def capture_all(self) -> List[ScreenshotResult]:
        """Capture screenshots for all configured schemes.

        Returns:
            List of ScreenshotResult objects (one per scheme attempted).
        """
        try:
            from playwright.async_api import async_playwright, Error as PlaywrightError
        except ImportError:
            logger.warning("playwright not installed — screenshots disabled")
            return []

        results: List[ScreenshotResult] = []

        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--ignore-certificate-errors",
                    ],
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to launch Chromium: %s", exc)
                return []

            try:
                for scheme in self.schemes:
                    result = await self._capture_one(browser, scheme)
                    results.append(result)
            finally:
                try:
                    await browser.close()
                except Exception:  # noqa: BLE001
                    pass

        return results

    async def _capture_one(self, browser: object, scheme: str) -> ScreenshotResult:
        """Capture a single screenshot for a scheme.

        Args:
            browser: Playwright Browser instance.
            scheme: URL scheme to use.

        Returns:
            ScreenshotResult for this attempt.
        """
        from playwright.async_api import Browser, Error as PlaywrightError

        port = 443 if scheme == "https" else 80
        result = ScreenshotResult(host=self.host, scheme=scheme, port=port)
        url = f"{scheme}://{self.host}/"
        screenshot_path = self.screenshots_dir / _safe_filename(self.host, scheme)

        context = None
        page = None
        try:
            context = await browser.new_context(  # type: ignore[attr-defined]
                viewport={"width": self.viewport_width, "height": self.viewport_height},
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (compatible; RECON-X/1.0; Security Scanner)",
            )
            page = await context.new_page()

            # Navigate with timeout
            response = await page.goto(
                url,
                timeout=self.page_timeout,
                wait_until="networkidle",
            )

            result.final_url = page.url
            result.page_title = await page.title()
            result.status_code = response.status if response else None

            # Capture screenshot
            await page.screenshot(
                path=str(screenshot_path),
                full_page=self.full_page,
            )
            result.screenshot_path = str(screenshot_path)
            logger.info("Screenshot saved: %s", screenshot_path)

        except PlaywrightError as exc:
            result.error = str(exc)
            logger.debug("Screenshot failed for %s://%s: %s", scheme, self.host, exc)
        except Exception as exc:  # noqa: BLE001
            result.error = str(exc)
            logger.debug("Screenshot unexpected error %s://%s: %s", scheme, self.host, exc)
        finally:
            if page:
                try:
                    await page.close()
                except Exception:  # noqa: BLE001
                    pass
            if context:
                try:
                    await context.close()
                except Exception:  # noqa: BLE001
                    pass

        return result
