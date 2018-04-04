# Nutcracker

This project demonstrates several practical attacks on the Walnut signature scheme.

## Compiling and running the code 

```
cd this_directory
make
./main
```

## Choosing the attack 

The main function contains the code below. Uncomment a function to demonstrate the corresponding attack. The security level is defined in the api.h file and can be changed (only 128 or 256 bits). 

```
// Demonstrates Walnut
//walnutDemo(1);

// Doing a collision search to find two messages that have the same signatures.
//collisionAttack();

// Demonstrates solving a REM instance 
solveREMDemo();

// A key recovery attack by solving two REM instances
//Attack();

// A universal signature forgery by solving one REM instance
//ForgeryAttack();
```
