<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header("Content-Type: application/json");

$host = "MySQL-8.0";
$db_name = "rest_api";
$username = "root";
$password = "";
$conn = null;

try {
    $conn = new PDO("mysql:host=$host;dbname=$db_name", $username, $password);
    $conn->exec("set names utf8");
} catch (PDOException $exception) {
    echo json_encode(["message" => "Connection error: " . $exception->getMessage()]);
    exit();
}

$requestMethod = $_SERVER["REQUEST_METHOD"];
$input = json_decode(file_get_contents("php://input"), true);

file_put_contents('php://stderr', print_r($input, TRUE));

switch ($requestMethod) {
    case 'POST':
        if (isset($input['action']) && $input['action'] === 'login') {
            login($input);
        } else {
            createUser($input);
        }
        break;
    case 'PUT':
        updateUser($input);
        break;
    case 'DELETE':
        deleteUser($input);
        break;
    case 'GET':
        if (isset($_GET['id'])) {
            getUser($_GET['id']);
        } else {
            echo json_encode(["message" => "User ID is required"]);
        }
        break;
    default:
        echo json_encode(["message" => "Invalid request method"]);
        break;
}

function createUser($data)
{
    global $conn;
    if (!isset($data['username']) || !isset($data['email']) || !isset($data['password'])) {
        echo json_encode(["message" => "Invalid input"]);
        return;
    }

    $query = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
    $stmt = $conn->prepare($query);

    $stmt->bindParam(':username', $data['username']);
    $stmt->bindParam(':email', $data['email']);
    $stmt->bindParam(':password', password_hash($data['password'], PASSWORD_BCRYPT));

    if ($stmt->execute()) {
        echo json_encode(["message" => "User created"]);
    } else {
        echo json_encode(["message" => "Unable to create user"]);
    }
}

function updateUser($data)
{
    global $conn;
    if (!isset($data['id']) || !isset($data['username']) || !isset($data['email']) || !isset($data['password'])) {
        echo json_encode(["message" => "Invalid input"]);
        return;
    }

    $query = "UPDATE users SET username = :username, email = :email, password = :password WHERE id = :id";
    $stmt = $conn->prepare($query);

    $stmt->bindParam(':id', $data['id']);
    $stmt->bindParam(':username', $data['username']);
    $stmt->bindParam(':email', $data['email']);
    $stmt->bindParam(':password', password_hash($data['password'], PASSWORD_BCRYPT));

    if ($stmt->execute()) {
        echo json_encode(["message" => "User updated"]);
    } else {
        echo json_encode(["message" => "Unable to update user"]);
    }
}

function deleteUser($data)
{
    global $conn;
    if (!isset($data['id'])) {
        echo json_encode(["message" => "Invalid input"]);
        return;
    }

    $query = "DELETE FROM users WHERE id = :id";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':id', $data['id']);

    if ($stmt->execute()) {
        echo json_encode(["message" => "User deleted"]);
    } else {
        echo json_encode(["message" => "Unable to delete user"]);
    }
}

function login($data)
{
    global $conn;
    if (!isset($data['email']) || !isset($data['password'])) {
        echo json_encode(["message" => "Invalid input"]);
        return;
    }

    $query = "SELECT * FROM users WHERE email = :email";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $data['email']);

    if ($stmt->execute() && $stmt->rowCount() > 0) {
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (password_verify($data['password'], $user['password'])) {
            echo json_encode(["message" => "Login successful", "user" => $user]);
        } else {
            echo json_encode(["message" => "Invalid password"]);
        }
    } else {
        echo json_encode(["message" => "User not found"]);
    }
}

function getUser($id)
{
    global $conn;
    $query = "SELECT * FROM users WHERE id = :id";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':id', $id);

    if ($stmt->execute() && $stmt->rowCount() > 0) {
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        echo json_encode($user);
    } else {
        echo json_encode(["message" => "User not found"]);
    }
}
?>