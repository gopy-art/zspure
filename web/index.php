<?php
include './scripts/controller.php';

function getUniqueCategories($devices)
{
    $categories = [];
    foreach ($devices as $device) {
        if (isset($device['data']['category'])) {
            $categories[] = $device['data']['category'];
        }
    }
    return array_values(array_unique($categories));
}

$CATEGORIES = getUniqueCategories($DEVICES);
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
    <ul class="nav justify-content-center border border-bottom-1 mb-5">
        <li class="nav-item">
            <a class="nav-link fs-1 text-dark fw-semibold" aria-current="page" href="/">ZSPURE</a>
        </li>
    </ul>

    <div class="container">
        <div class="row justify-content-center align-items-start">
            <?php foreach ($CATEGORIES as $key => $value): ?>
                <div class="col-12 col-md-6 col-lg-4 mb-4 d-flex justify-content-center">
                    <a href="#" class="text-decoration-none text-dark fs-4 fw-semibold border border-secondary rounded bg-light d-flex justify-content-center align-items-center"
                        style="width: 100%; height: 200px; max-width: 300px;">
                        <p class="mb-0 text-center"><?php echo $value; ?></p>
                    </a>
                </div>
            <?php endforeach ?>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-FKyoEForCGlyvwx9Hj09JcYn3nv7wiPVlz7YYwJrWVcXK/BmnVDxM+D2scQbITxI" crossorigin="anonymous"></script>
</body>

</html>