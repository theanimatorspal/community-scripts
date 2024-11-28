function describeObject(object) {
  try {
    print("========= Methods of " + object.getClass().getName() + " =========");
    var methods = Java.from(object.getClass().getDeclaredMethods()); // Convert Java array to iterable JavaScript array
    for (var i = 0; i < methods.length; i++) {
      var method = methods[i];
      var paramTypes = Java.from(method.getParameterTypes()); // Convert parameter types to JavaScript array
      var params = paramTypes.map(p => p.getName()); // Get parameter type names
      print(method.getName() + "(" + params.join(", ") + ")");
    }
    print("--- Fields ---");
    var fields = Java.from(object.getClass().getDeclaredFields()); // Convert Java array to iterable JavaScript array
    for (var i = 0; i < fields.length; i++) {
      var field = fields[i];
      print(field.getName() + " : " + field.getType().getName());
    }
    print("========= End =========");
  } catch (e) {
    print("Caught " + e);
    for (var stack of e.getStackTrace()) {
      print(stack);
    }
  }
}

function getFieldByReflection(object, fieldName) {
  try {
    var field = object.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.get(object);
  } catch (e) {
    print("Error accessing field: " + fieldName);
    print("Caught " + e);
    for (var stack of e.getStackTrace()) {
      print(stack);
    }
  }
}

function getMethodByReflection(object, methodName) {
  try {
    var methods = Java.from(object.getClass().getDeclaredMethods()); // Convert to iterable JavaScript array
    for (var i = 0; i < methods.length; i++) {
      if (methods[i].getName() === methodName) {
        methods[i].setAccessible(true);
        return methods[i];
      }
    }
    throw new Error("Method " + methodName + " not found");
  } catch (e) {
    print("Error getting method: " + methodName);
    print("Caught " + e);
    for (var stack of e.getStackTrace()) {
      print(stack);
    }
  }
}

function invokeMethod(object, methodName, ...args) {
  try {
    var method = getMethodByReflection(object, methodName);
    return method.invoke(object, args);
  } catch (e) {
    print("Error invoking method: " + methodName);
    print("Caught " + e);
    for (var stack of e.getStackTrace()) {
      print(stack);
    }
  }
}

function listInterfaces(object) {
  try {
    print("========= Interfaces of " + object.getClass().getName() + " =========");
    var interfaces = Java.from(object.getClass().getInterfaces()); // Convert to iterable JavaScript array
    for (var i = 0; i < interfaces.length; i++) {
      print(interfaces[i].getName());
    }
    print("========= End =========");
  } catch (e) {
    print("Error listing interfaces");
    print("Caught " + e);
    for (var stack of e.getStackTrace()) {
      print(stack);
    }
  }
}

function listSuperClasses(object) {
  try {
    print("========= Superclasses of " + object.getClass().getName() + " =========");
    var superclass = object.getClass().getSuperclass();
    while (superclass != null) {
      print(superclass.getName());
      superclass = superclass.getSuperclass();
    }
    print("========= End =========");
  } catch (e) {
    print("Error listing superclasses");
    print("Caught " + e);
    for (var stack of e.getStackTrace()) {
      print(stack);
    }
  }
}

function listConstructors(object) {
  try {
    print("========= Constructors of " + object.getClass().getName() + " =========");
    var constructors = Java.from(object.getClass().getDeclaredConstructors()); // Convert to iterable JavaScript array
    for (var i = 0; i < constructors.length; i++) {
      var paramTypes = Java.from(constructors[i].getParameterTypes()); // Convert parameter types to JavaScript array
      var params = paramTypes.map(p => p.getName());
      print(constructors[i].getName() + "(" + params.join(", ") + ")");
    }
    print("========= End =========");
  } catch (e) {
    print("Error listing constructors");
    print("Caught " + e);
    for (var stack of e.getStackTrace()) {
      print(stack);
    }
  }
}

function loadExtension(extensionName) {
  try {
    var extension = control.getExtensionLoader().getExtension(extensionName);
    if (extension == null) {
      print("Extension " + extensionName + " not found or not loaded.");
    } else {
      print("Extension " + extensionName + " loaded successfully: " + extension.getClass().getName());
    }
    return extension;
  } catch (e) {
    print("Error loading extension: " + extensionName);
    print("Caught " + e);
    for (var stack of e.getStackTrace()) {
      print(stack);
    }
  }
}

function listLoadedExtensions() {
  try {
    print("========= Loaded Extensions =========");
    var extensions = Java.from(control.getExtensionLoader().getExtensions()); // Convert to iterable JavaScript array
    for (var i = 0; i < extensions.length; i++) {
      print(extensions[i].getName() + " : " + extensions[i].getClass().getName());
    }
    print("========= End =========");
  } catch (e) {
    print("Error listing loaded extensions");
    print("Caught " + e);
    for (var stack of e.getStackTrace()) {
      print(stack);
    }
  }
}
