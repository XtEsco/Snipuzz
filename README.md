# Snipuzz
A blackbox network fuzzer for IoT devices.

This work is published on CCS'21 [Snipuzz: Black-box Fuzzing of IoT Firmware via Message Snippet Inference](https://dl.acm.org/doi/10.1145/3460120.3484543).

Snipuzz runs as a client communicating with the devices and infers message snippets for mutation based on the responses. Each snippet refers to a block of consecutive bytes that reflect the approximate code coverage in fuzzing. This mutation strategy based on message snippets considerably narrows down the search space to change the probing messages. 

We are adding the user manual to help use Snipuzz. And we are working on re-implement Snipuzz with python.

# Python version
Please find our python version of this project in [Snipuzz-py](https://github.com/Immor278/Snipuzz-py), which will be maintained in the future.
