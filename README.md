# csgp - a supergenpass.com implementation in c

## usage

    $> csgp -domain="example.com"
    password: 1
    dlHhFkN3vr

    $> csgp -domain="example.com"
    password: 2
    lnJs5E571V

## build

you will need a c-compiler and cmake. after you have installed
both and got them working:

unix:

    $> ( mkdir build && cd build && cmake .. )
    $> make -C build

windows:

    $> mkdir build
    $> cd build
    $> cmake.exe ..
    $> devenv.exe csgp.sln /build "Release"

or open the the created .sln file in visualstudio
