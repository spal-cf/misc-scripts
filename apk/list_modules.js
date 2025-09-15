// list_modules.js
function listModules() {
  console.log("Loaded Modules:");
  Process.enumerateModules().forEach(function(module) {
    console.log("Name:", module.name);
    console.log("Base Address:", module.base);
    console.log("Size:", module.size);
    console.log("Path:", module.path);
    console.log("------------------------");
  });
}

// Call the function when the script is attached
listModules();
