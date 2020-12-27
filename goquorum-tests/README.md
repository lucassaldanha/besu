# Besu <> GoQuorum Integration Tests

This is a simple setup showing how we can use testcontainers to manage containers from our tests.

The class ContainerTest is starting a Besu docker container, and using Web3j to call an API method.

We should be able to have containers with each one of the services that we need (Besu, GoQuorum and Tessera).
Another option would be using a Docker compose file with a network ready to be used.

One thing that has to be done is properly setting up a sourceset and preventing the test to run with the
"regular" unit tests of the project. We want this to run as a separate task.

I hope this helps :)