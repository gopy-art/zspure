<?php
/*
Gather all the json information that will be exist in the devices/services modules in the
project directory and push all the json as one global variable and use it other pages!
*/
function getDeviceDataRecursive(string $dir) {
    // raplace the directory separator base on the operating system!
    $dir = str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $dir);
    
    $results = [];
    $items = scandir($dir);
    
    foreach ($items as $item) {
        if ($item == '.' || $item == '..') continue;
        
        $fullPath = $dir . DIRECTORY_SEPARATOR . $item;
        
        if (is_dir($fullPath)) {
            $jsonFiles = glob($fullPath . DIRECTORY_SEPARATOR . '*.json');
            
            if (!empty($jsonFiles)) {
                $jsonFile = $jsonFiles[0];
                $jsonData = json_decode(file_get_contents($jsonFile), true);
                
                $imageFiles = array_merge(
                    glob($fullPath . DIRECTORY_SEPARATOR . '*.png'),
                    glob($fullPath . DIRECTORY_SEPARATOR . '*.jpg'),
                    glob($fullPath . DIRECTORY_SEPARATOR . '*.jpeg')
                );
                
                $results[] = [
                    'data' => $jsonData,
                ];
            } else {
                $results = array_merge($results, getDeviceDataRecursive($fullPath));
            }
        }
    }
    
    return $results;
}

$rootDir = "../modules";
$DEVICES = getDeviceDataRecursive($rootDir);
?>