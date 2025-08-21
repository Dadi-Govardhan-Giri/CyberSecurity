def password_score(password: str) -> int:
    score = 0

    if any(c.isdigit() for c in password):
        score += 2.5
    if any(c.islower() for c in password):
        score += 2.5
    if any(c.isupper() for c in password):
        score += 2.5
    if any(not c.isalnum() for c in password):
        score += 2.5

    return int(score)

password = input("Enter the password: ")
print(f"The score of the password: {password_score(password)}/10")
print("Use --> LowerCase Alphabets , UpperCase Alphabets , Special Symbols , Numbers")
