# RecursiveDnsServer

Make the project using 'make'
Run the hw4 obj file as follows:
  ./hw4 -p {port_no}
  
The server can be queried using dig.
  dig @localhost -p {port_no_same_as_above} {lookup_url}
  
Example usage:
  ./hw4 -p 4045
  dig @localhost -p 4045 www.google.com
