from pathlib import Path
from typing import Optional

import typer

from .translate import translate


app = typer.Typer()


@app.command()
def main(qvm: Path, maps: Optional[list[Path]] = typer.Argument(None)):
    translate(
        qvm,
        maps,
        qvm.with_suffix(".xml"),
        qvm.with_suffix(".bytes"),
    )
