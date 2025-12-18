Development
=============

Debugging mode
----------------

aionetiface has a simple log file that is written to when ~/aionetiface/logs exists. 

Running tests
----------------

aionetiface has unit tests to check basic functionality works. These tests offer helpful
hints if individual components are working on different platforms. Though
the tests tend not to be as well maintained as the main project; Located in the
tests folder. The normal way to run them is to change to the tests directory
and run:

.. parsed-literal:: 
    python3 -m unittest

Individual files can also be run and individual tests ran by executing:

.. parsed-literal:: 
    python3 -m unittest file_name.ClassName.test_func_name

I have briefly experimented with running tests concurrently for speed. 

.. parsed-literal:: 
    python3 -m pip install -U pytest
    python3 -m pip install pytest-asyncio
    python3 -m pip install pytest-xdist
    pytest -n 8

Building the docs 
--------------------

These docs use restructured text and need some dependencies to build.

.. parsed-literal:: 
    python3 -m pip install sphinx
    python3 -m pip install myst-parser
    python3 -m pip install sphinx_rtd_theme
    python3 -m pip install readthedocs-sphinx-search

The docs can be built with this command:

.. parsed-literal:: 
    cd docs
    python3 -m sphinx.cmd.build source html

Then you can open html/index.html.