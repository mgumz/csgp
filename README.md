# csgp - a supergenpass.com implementation in c

<a href="https://scan.coverity.com/projects/mgumz-csgp">
  <img alt="Coverity Scan Build Status" src="https://scan.coverity.com/projects/7723/badge.svg"/>
</a>

*csgp* is a command line tool to create domain-specific passwords based
upon one master password. the algorithm used is the same as [supergenpass][1].

advantages of using *csgp* instead of the javascript-based version:

* it separates password-generation from password-use, the browser (or other
  authentification means) will never get near the master-password.
* it minimizes the amount of ram used to an absolutely minimum
* it zeros the used ram before exiting (other programs started later
  won't see leftovers of *csgp*)
* it tries to lock the ram so it won't get swapped out to disk. i do not
  consider this a major problem because *csgp* can be compiled into a ~75k
  static executable on windows or into a ~15kb static executable using 
  [dietlibc][3] on linux and it uses only a handful of bytes (allocated on the
  stack, not the heap) to do it's job.


concerns of using supergenpass:

* [bookmarklet][1]: makes it very easy to use it via a bookmarklet, directly on
  the page. since you are typing the password into a field on that page, any
  event-handler listening for keypresses on that field might snoop away
  the master password.

* [supergenpass-mobile][2]: this is a separate page, opened in a separate
  browser-tab or -window and thus should not be subject to the former
  "problem". but, the implementation is using javascript where you have
  actually no control about where pieces of the master-password or the
  derived password end up in ram. once you close that window: is really
  all of the ram beeing securely cleaned? no one knows for sure.

as always: convinience vs security.

## usage

create a password for the domain "example.com":

    $> csgp -domain="example.com"
    password: 1
    dlHhFkN3vr

use the same master password for different domains:

    $> csgp -domain="example.com"
    password: 2
    lnJs5E571V

    $> csgp -domain="github.io"
    password: 2
    j78DM1hKP9

create a password for "example.com" and pipe it to the clipboard
on macosx:

    $> csgp -domain="example.com" | pbcopy
    password: 1

the password is now in the clipboard and can be pasted into the
login-form of "example.com"


## build

you will need a c-compiler. tested compilers:

* gcc-4.x (linux-386, linux-x64)
* clang-3.x (freebsd-10.1, macosx-10.7)
* visualstudio2013 (win8.1)

other should work too, the code should be pretty portable.

### unix

simple and plain make:

    $> make

simple and plain cmake:

    $> ( mkdir build && cd build && cmake .. )
    $> make -C build

or a one-liner:

    $> gcc -Os -o csgp main.c md5.c base64.c \
        platform.c platform_unix.c \
        djb/*.c

or (using [dietlibc][3] to create a 15k static binary on linux):

    $> diet -Os gcc -o csgp main.c md5.c base64.c \
        platform.c platform_unix.c \
        djb/*.c

### windows:

simple and plain cmake:

    $> mkdir build
    $> cd build
    $> cmake.exe ..

and then

    $> devenv.exe csgp.sln /build "Release"

or open the the created .sln file in visualstudio. or use nmake:

    $> mkdir build-nmake
    $> cd build-nmake
    $> cmake.exe -G "NMake Makefiles"
    $> nmake


[1]: http://supergenpass.com/
[2]: https://chriszarate.github.io/supergenpass/mobile/
[3]: https://www.fefe.de/dietlibc/
