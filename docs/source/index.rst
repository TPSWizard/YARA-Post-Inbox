YARA Rules & Tips! **This page is under construction**
===================================

What are "YARA" rules?
YARA rules are text files with a very basic, yet powerful, syntax. These rules contain three parts:

Each rule in YARA starts with the keyword rule followed by a rule identifier. Identifiers must follow the same lexical conventions of the C programming language, they can contain any alphanumeric character and the underscore character, but the first character cannot be a digit. Rule identifiers are case sensitive and cannot exceed 128 characters. The following keywords are reserved and cannot be used as an identifier:

Meta: Background information regarding rule - Not processed
Strings: Pieces of information being searched for in our target email.
Conditions: Defines the condition for matching. It can be just matching one or several strings. (Are my strings "true?)

Quick Sample Rule Template:

.. code-block:: yara

    rule rulename_sample
    {
        meta:
            description = "This is just an example"
            version="0.1"
            date="2021/05/12"
   
        strings:
            $my_hex_string = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
            $my_text_string = "text here"
            
        condition:
            $my_text_string or $my_hex_string
            /* This is a comment :) */
    }
    
    

Some Sample Rules:
================================

Each rule in YARA starts with the keyword ``rule`` followed by a rule
identifier. Identifiers must follow the same lexical conventions of the C
programming language, they can contain any alphanumeric character and the
underscore character, but the first character cannot be a digit. Rule
identifiers are case sensitive and cannot exceed 128 characters. The following
keywords are reserved and cannot be used as an identifier:

.. list-table::
   :widths: 10 10 10 10 10 10 10 10

   * - all
     - and
     - any
     - ascii
     - at
     - base64
     - base64wide
     - condition
   * - contains
     - endswith
     - entrypoint
     - false
     - filesize
     - for
     - fullword
     - global
   * - import
     - icontains
     - iendswith
     - iequals
     - in
     - include
     - int16
     - int16be
   * - int32
     - int32be
     - int8
     - int8be
     - istartswith
     - matches
     - meta
     - nocase
   * - none
     - not
     - of
     - or
     - private
     - rule
     - startswith
     - strings
   * - them
     - true
     - uint16
     - uint16be
     - uint32
     - uint32be
     - uint8
     - uint8be
   * - wide
     - xor
     - defined
     -
     -
     -
     -
     -
     
Sample Rule 1 | Generic Email Spamming
================================

.. code-block:: yara

   rule CountExample
   {
            meta:
            description = "Generic rule to identify phishing emails"
            
            strings:
            $eml_1="From:"
            $eml_2="To:"
            $eml_3="Subject:"

            $greeting_1="Hello sir/madam" nocase
            $greeting_2="Attention" nocase
            $greeting_3="Dear user" nocase
            $greeting_4="Account holder" nocase

            $url_1="Click" nocase
            $url_2="Confirm" nocase
            $url_3="Verify" nocase
            $url_4="Here" nocase
            $url_5="Now" nocase
            $url_6="Change password" nocase 

            $lie_1="Unauthorized" nocase
            $lie_2="Expired" nocase
            $lie_3="Deleted" nocase
            $lie_4="Suspended" nocase
            $lie_5="Revoked" nocase
            $lie_6="Unable" nocase
            
            condition:
            all of ($eml*) and
            any of ($greeting*) and
            any of ($url*) and
            any of ($lie*)
    }  


Sample Rule 2
================================

.. code-block:: yara

   rule CountExample
   {
            meta:
            description = "This is just an example"
            
            strings:
            $a = "dummy1"
            $b = "dummy2"
            
            condition:
            #a == 6 and #b > 10
    }
    
Sample Rule 3
================================

.. code-block:: yara

   rule CountExample
   {
            meta:
            description = "This is just an example"
            
            strings:
            $a = "dummy1"
            $b = "dummy2"
            
            condition:
            #a == 6 and #b > 10
    }  
    
    
    
    
Working Import Modules
================================    
Section in Progress
