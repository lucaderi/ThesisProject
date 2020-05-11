# ThesisProject [Draft]
Modelling user network behaviour through network traffic analysis.

## DataInterpreter.py
Interprets data from text files generated by nProbe.

### Prerequisites
Python modules required to run the program: 
* recordclass 
* netifaces
* ipaddress
* py-radix
* csv

To install a module using pip, just run:

```
pip install modulename
```

The program works on textfiles generated from nProbe, which have a special format.

### Usage
The program takes as argument the directory where the nProbe text files that the user wants to analyse have been saved.
For example, if I want to analyse data of all text files contained in directory with path *dirpath*, I run:

```
python3 DataInterpreter.py /dirpath 
```

The program will create in the current directory a file named **prova.csv** containing the collected data properly sorted. 
