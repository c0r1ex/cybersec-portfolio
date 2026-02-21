Challenge Writeup: Food Order Insecure Deserialization

# 1. Enumeration & Discovery

The initial scan revealed an Apache server running PHP 7.4.33. After registering and logging in, the core functionality was found in `order.php.`

Vulnerability identified: The application takes a `POST` parameter named `data`, decodes it from Base64, and passes it into the `unserialize()` function.

The Goal: Find a way to use existing classes (gadgets) to reach a dangerous function like `system().`

# 2. Identifying Gadgets

By analyzing the source code files, four key components were identified to build an exploitation chain:

![[Pasted image 20260204224327.png]]

# 3. Constructing the POP Chain

The "domino effect" was constructed by nesting these objects within one another:

Entry Point: When the script finishes, the `Pizza` object is destroyed. Its destructor tries to read a property from `$size.`

The Jump: By setting `$size` to a `Spaghetti` object, the attempt to read `what` (which doesn't exist in `Spaghetti`) triggers `__get().`

The Call: `Spaghetti` then executes its `$sauce` as a function. By setting `$sauce` to an `IceCream` object, the `__invoke()` method is triggered.

The Loop: `IceCream` starts a `foreach` loop. If its `$flavors` property is an `ArrayHelpers` object, PHP calls the `current()` method to get the loop values.

The Sink (RCE): Inside `current()`, the code runs `call_user_func($this->callback, $value)`. By setting `callback` to `system` and the array value to a Linux command, Remote Code Execution is achieved.

# 4. Exploitation

A custom PHP script was used to generate the serialized payload:

Step A: Define the classes and their namespaces (specifically `namespace Helpers` for `ArrayHelpers).`

Step B: Instantiate the objects and link them: `Pizza -> Spaghetti -> IceCream -> ArrayHelpers.`

Step C: Set the command to `ls /` to find the flag, then Base64 encode the result.

Execution:
- Intercepted the `/order.php` request.
- Replaced the `data` parameter with the generated payload.
- Located the randomized flag file: `/pBhfMBQlu9uT_flag.txt.`
- Updated the payload command to `cat /pBhfMBQlu9uT_flag.txt.`
- The server returned the flag in the HTTP response.