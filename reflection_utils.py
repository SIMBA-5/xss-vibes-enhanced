def find_reflection(response: str, marker: str, window: int = 120):
    """
    Return the first reflection position and a small surrounding snippet.
    """
    position = response.find(marker)

    if position == -1:
        return None, None

    start = max(0, position - window)
    end = min(len(response), position + len(marker) + window)

    return position, response[start:end]


def is_reflected(response: str, marker: str) -> bool:
    return response.find(marker) != -1
