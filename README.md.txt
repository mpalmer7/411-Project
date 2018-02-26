A project for one of my classes. The goal is to read a binary file in a specified format and write the output in htlm.
The script had to be written in a way such that it would not crash if malicious input was entered.

The format of the input file is listed below. 

| Tag (1 byte)  | Length        | Data          | Notes                |
|:-------------:|:-------------:|:-------------:|:--------------------:|
| 0             | N/A           | N/A           | indicate end of data |
| 1             | 4 Bytes       |length of  data| (in bytes)           |
| 2             | N/A		| 32 bit integer|                      | 
| 3             | N/A	        | 16 bit integer|                      |
| 4             | N/A	        | 8 bit integer |                      |
| 5             | N/A           | N/A           | print record         |

The file must be run with an input file like so:
`./project1 "binary_input_file.bin"`