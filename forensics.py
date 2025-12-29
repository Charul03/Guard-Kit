import os
import datetime
import mimetypes

def file_metadata(filepath: str) -> dict:
    st = os.stat(filepath)
    return {
        'path': os.path.abspath(filepath),
        'size_bytes': st.st_size,
        'created': datetime.datetime.fromtimestamp(st.st_ctime).isoformat(),
        'modified': datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
        'mime': mimetypes.guess_type(filepath)[0] or 'unknown',
        'mode': oct(st.st_mode)
    }

def hex_preview(filepath: str, length: int = 256) -> str:
    with open(filepath, 'rb') as f:
        chunk = f.read(length)
    return chunk.hex()
