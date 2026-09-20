from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


SUPPORTED_DIALOGS = {"alert", "confirm", "prompt"}


def browser_verify(url: str, timeout_ms: int = 5000) -> dict:
    """
    Browser-side verification for authorized security labs/targets.

    A finding is considered browser-verified only when Chromium observes
    an alert, confirm, or prompt dialog while loading the exact result URL.

    This is evidence of browser-side execution, not a universal proof that
    every XSS payload is exploitable in every browser/context.
    """

    result = {
        "browser_verified": False,
        "browser_started": False,
        "page_loaded": False,
        "dialog_detected": False,
        "dialog_type": None,
        "dialog_message": None,
        "verification_reason": None,
        "final_url": None,
        "error": None,
    }

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            result["browser_started"] = True

            page = browser.new_page()

            def handle_dialog(dialog):
                result["dialog_detected"] = True
                result["dialog_type"] = dialog.type
                result["dialog_message"] = dialog.message

                if dialog.type in SUPPORTED_DIALOGS:
                    result["browser_verified"] = True
                    result["verification_reason"] = (
                        f"Chromium observed a {dialog.type} dialog"
                    )
                else:
                    result["verification_reason"] = (
                        f"Chromium observed unsupported dialog type: {dialog.type}"
                    )

                dialog.dismiss()

            page.on("dialog", handle_dialog)

            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )

            result["page_loaded"] = True
            result["final_url"] = page.url

            # Give immediate JavaScript a short window to trigger a dialog.
            page.wait_for_timeout(500)

            if not result["dialog_detected"]:
                result["verification_reason"] = (
                    "No supported JavaScript dialog observed during page load"
                )

            browser.close()

    except PlaywrightTimeoutError:
        result["error"] = "page-load-timeout"
        result["verification_reason"] = "Browser navigation timed out"

    except Exception as exc:
        result["error"] = str(exc)
        result["verification_reason"] = "Browser verification failed"

    return result
