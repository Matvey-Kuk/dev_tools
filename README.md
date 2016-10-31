BMP Tools
---------

Various BMP released tools for working with BMP data.  These tools are intended for 
testing/validating BMP. 

## Bmp play using example:
1. Downloading script:
```
wget https://raw.githubusercontent.com/OpenBMP/dev_tools/master/bmp_play/bmp_play.py
```

2. Making BMP dump from router:
```
python bmp_play.py -m record -p 5000 -f router_bmp.dump
```

3. Playing dump to collector:
```
python bmp_play.py -m play -p 5000 -f router_bmp.dump -d 127.0.0.1
```

4. Figuring out arguments:
```
python bmp_play.py -h
```
