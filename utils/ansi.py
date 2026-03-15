RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GRAY = "\033[90m"

def color(text: str, *codes: str) -> str:
    try:
        return f"{''.join(codes)}{text}{RESET}"
    except Exception:
        return text

