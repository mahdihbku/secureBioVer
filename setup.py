from distutils.core import setup, Extension


crypto_lib_module = Extension('_crypto_lib',
                           sources=['crypto_lib_wrap.c', 'crypto_lib.c'],
                           libraries=['lcrypto','lssl'],
                           )

setup (name = 'crypto_lib',
       version = '0.1',
       author      = "SWIG Docs",
       description = """Simple swig crypto_lib from docs""",
       ext_modules = [crypto_lib_module],
       py_modules = ["crypto_lib"],
       )
