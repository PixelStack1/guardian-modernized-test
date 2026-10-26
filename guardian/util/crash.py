import time
import traceback
from pathlib import Path

from util.paths import data_file


def crash_report(
    exception: Exception,
    additional: str | None = None,
    filename: str | None = None,
) -> None:
    if filename is None:
        filename = f"crashreport_{hex(int(time.time_ns()))[2:]}.log"

    path = Path(filename) if Path(filename).is_absolute() else data_file(filename)
    with path.open("w") as handle:
        handle.write(
            f"Report local time: {time.asctime(time.localtime())}\nReport UTC time:   {time.asctime(time.gmtime())}\n\n"
        )
        handle.write(f"Error: {exception}\n\n")
        handle.write(f"{traceback.format_exc()}\n")

        if additional is not None:
            handle.write(f"\nAdditional info: {additional}\n")
