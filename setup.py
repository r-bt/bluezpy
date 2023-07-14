from distutils.core import setup, Extension

def main():
    setup(
        name="bluezpy",
        version="0.1",
        description="Python wrapper for BlueZ",
        author="Richard Beattie",
        author_email="rbeattie@mit.edu",
        ext_modules=[Extension("bluezpy", ["bluezpymodule.cpp"], extra_link_args=['-lbluetooth'], libraries = ['bluetooth'])],
    )

if __name__ == "__main__":
    main()