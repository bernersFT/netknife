try:
    from importlib.metadata import version, PackageNotFoundError
    __version__ = version("netknife")
except PackageNotFoundError:  # during editable/dev
    __version__ = "1.1.0"