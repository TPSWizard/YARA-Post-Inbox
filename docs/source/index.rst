YARA Rules & Tips! **This page is under construction**
===================================

What are "YARA" rules?
YARA rules are text files with a very basic, yet powerful, syntax. These rules contain three parts:

Each rule in YARA starts with the keyword rule followed by a rule identifier. Identifiers must follow the same lexical conventions of the C programming language, they can contain any alphanumeric character and the underscore character, but the first character cannot be a digit. Rule identifiers are case sensitive and cannot exceed 128 characters. The following keywords are reserved and cannot be used as an identifier:

Meta: Background information regarding rule - Not processed
Strings: Pieces of information being searched for in our target email.
Conditions: Defines the condition for matching. It can be just matching one or several strings. (Are my strings "true?)

Quick Rule Template:

rule insertrulename
{
   meta:
         author="name"
         version="0.1"
         date="2021/05/12"
         reference="any useful reference"
strings:

condition:
}


===================================
.. note::

   This project is under active development.

Contents
--------

.. toctree::

   usage
   api


Some Sample Rules:
================================

YARA is a tool aimed at (but not limited to) helping malware researchers to
identify and classify malware samples. With YARA you can create descriptions of malware families (or whatever you want to describe) based on textual or binary patterns. Each description, a.k.a. rule, consists of a set of strings and a
boolean expression which determine its logic. Let's see an example:

.. code-block:: yara

    rule silent_banker : banker
    {
        meta:
            description = "This is just an example"
            threat_level = 3
            in_the_wild = true
        strings:
            $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
            $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
            $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
        condition:
            $a or $b or $c
    }

The above rule is telling YARA that any file containing one of the three strings
must be reported as silent_banker. This is just a simple example, more complex
and powerful rules can be created by using wild-cards, case-insensitive strings, regular expressions, special operators and many other features that you'll find explained in this documentation.

Contents:

.. toctree::
   :maxdepth: 3

   gettingstarted
   writingrules
   modules
   writingmodules
   commandline
   yarapython
   capi


