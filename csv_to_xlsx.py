import pandas as pd

df = pd.read_csv("recommendations.csv")
df.to_excel("recommendations.xlsx", index=False)
print("[✓] Created recommendations.xlsx")
