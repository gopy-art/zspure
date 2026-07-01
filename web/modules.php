<?php
include __DIR__ . '/scripts/controller.php';

$queryString = $_SERVER['QUERY_STRING'];
parse_str($queryString, $params);
$q = $params['q'] ?? '';
if ($q == '')
    exit;
function getUniqueModules(array $devices, string $key)
{
    $modules = [];
    foreach ($devices as $device) {
        if (isset($device['data']['category']) && $device['data']['category'] == $key) {
            $modules[] = $device['data'];
        }
    }
    return array_values(array_unique($modules));
}

$Modules = getUniqueModules($DEVICES, $q);
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <title>Device/Service Documents</title>
</head>

<body>
    <ul class="nav justify-content-center border border-bottom-1 mb-4">
        <li class="nav-item">
            <a class="nav-link fs-1 text-dark fw-semibold" aria-current="page" href="/">ZSPURE</a>
        </li>
    </ul>

    <div class="container">
        <h2 class="text-center fw-semibold mb-5"> <?php echo $q; ?> </h2>
        <div class="row row-cols-1 row-cols-md-3 g-4">
            <?php foreach ($Modules as $key => $value) : ?>
                <div class="col mb-4">
                    <div class="card">
                        <?php if ($value["image"] != ""): ?>
                            <img src="<?php echo "/modules".$value["image"]; ?>" class="card-img-top" alt="...">
                        <?php endif ?>
                        <div class="card-body">
                            <h5 class="card-title fw-semibold"><?php echo $value["name"]; ?></h5>
                            <p class="mb-1"> <b>Protocol</b> : <?php echo $value["protocol"]; ?> </p>
                            <p class="card-text" style="font-size: 14px;"><?php echo $value["description"] ?></p>
                        </div>
                    </div>
                </div>
            <?php endforeach ?>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-FKyoEForCGlyvwx9Hj09JcYn3nv7wiPVlz7YYwJrWVcXK/BmnVDxM+D2scQbITxI" crossorigin="anonymous"></script>
</body>

</html>