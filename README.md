# xcoin-hash #
Python module for x11kvs PoW algorithm

To install:

    sudo python setup.py install

	
#windows (default compiler - mscv)

To build:

    python setup.py build -c mingw32	
	
	cp -f "C:\X11KVS-hash\build\lib.win32-3.7\x11kvs_hash.cp37-win32.pyd" "C:\Users\your_user\AppData\Local\Programs\Python\Python37-32\Lib\site-packages\"

	
To test:

	python test.py
	




---	QT 5.14 Tools /mingw 7.30 ---
To set default compiler.
	
	C:\Users\your_user\AppData\Local\Programs\Python\Python37-32\Lib\distutils\distutils.cfg :
	
	[build]
	compiler=mingw32
	
To build:

    python setup.py install
