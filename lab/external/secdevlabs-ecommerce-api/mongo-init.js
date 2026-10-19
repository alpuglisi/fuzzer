// secdevlabs-ecommerce-api's MongoDB user (CC-LAB-0315): what upstream's
// scripts/generate-passwords.sh writes, with this throwaway lab's fixed credentials
// (compose.yaml passes the same to the API). Run once, on the empty tmpfs data dir.
var db = connect("mongodb://localhost/DB");
db.createUser({user: "ecommerce", pwd: "ecommerce",
               roles: [{role: "userAdminAnyDatabase", db: "admin"}]});
