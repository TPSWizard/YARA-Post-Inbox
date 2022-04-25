YARA Rules & Tips!
===================================

What are "YARA" rules?
YARA rules are text files with a very basic, yet powerful, syntax. These rules contain three parts:

Meta: Background information regarding rule - Not processed
Strings: Pieces of information being searched for in our target email.
Conditions: Defines the condition for matching. It can be just matching one or several strings. (Are my strings "true?)

Quick Rule Template:
rule samplerule
{
   meta:
         author="Cedric Pernet"
version="0.1"
date="2021/05/12"
reference="any useful reference"
strings:
condition:
}





.. note::

   This project is under active development.

Contents
--------

.. toctree::

   usage
   api
