def calculate_total(price: float, tax_rate: float) -> float:
    """Calculate the total price including tax."""
    return price * (1 + tax_rate)

class User:
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role

    def is_admin(self) -> bool:
        return self.role == "admin"

if __name__ == "__main__":
    user = User("ion", "admin")
    print(f"Is admin: {user.is_admin()}")
    print(f"Total: {calculate_total(100.0, 0.21)}")