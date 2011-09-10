NVIDIA MODS kernel driver
=========================

Introduction
------------

The NVIDIA MODS kernel driver is a simple kernel module which provides
access to devices on the PCI bus for user mode programs.  It is so named
because it was originally written to support the MOdular Diagnostic Suite
(MODS), which is our internal chip diagnostic toolkit.

The MODS driver was never intended for release to the public, and as such,
the code is in something of an unfinished form.  It is released in the hopes
that it will save work for people who might otherwise need to implement such
a thing.

This software is not published as an official NVIDIA product.  NVIDIA will
provide no support for this source release; send any questions to my
*personal* e-mail address, joshua@joshuawise.com.  That said, I welcome
contributions from others who would clean up the style, port it forward to
newer kernel versions, or enhance it in any way!

And now, a word from our lawyers...
-----------------------------------

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.


