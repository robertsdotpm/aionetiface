import os
import pathlib
import inspect
import json
from .utility.utils import *

# Path to where the script is running from.
def get_script_parent():
    # .f_back moves up one frame to the function that called this one
    caller_frame = inspect.currentframe().f_back 
    
    # Get the filename from the caller's frame info
    filename = inspect.getframeinfo(caller_frame).filename
    
    parent = pathlib.Path(filename).resolve().parent
    return os.path.realpath(parent)

# Home dir / aionetiface.
def get_aionetiface_install_root():
    return os.path.realpath(
        os.path.join(
            os.path.expanduser("~"),
            "aionetiface"
        )
    )

# Installs aionetiface files into home dir.
# The software only needs this for using PDNS functions.
def copy_aionetiface_install_files_as_needed():
    # Make install dir if needed.
    install_root = get_aionetiface_install_root()
    pathlib.Path(install_root).mkdir(parents=True, exist_ok=True)


if __name__ == '__main__':
    pass

