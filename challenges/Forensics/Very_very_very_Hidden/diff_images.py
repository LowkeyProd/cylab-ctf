from PIL import Image
import numpy as np

img1 = Image.open("duck.png")
img2 = Image.open("evil_duck.png")

print(f"img1: size={img1.size}, mode={img1.mode}")
print(f"img2: size={img2.size}, mode={img2.mode}")

arr1 = np.array(img1)
arr2 = np.array(img2)

print(f"arr1 shape: {arr1.shape}, dtype: {arr1.dtype}")
print(f"arr2 shape: {arr2.shape}, dtype: {arr2.dtype}")

diff = (arr1 != arr2)
print(f"Total different elements: {np.sum(diff)}")

if np.sum(diff) > 0:
    diff_val = arr2.astype(int) - arr1.astype(int)
    print("Diff min:", np.min(diff_val), "max:", np.max(diff_val))
    # Let's see non-zero diffs
    nz = np.where(arr1 != arr2)
    print(f"Diff coordinates sample: y={nz[0][:10]}, x={nz[1][:10]}, c={nz[2][:10]}")
    for i in range(min(10, len(nz[0]))):
        y, x, c = nz[0][i], nz[1][i], nz[2][i]
        print(f"  ({x}, {y}, ch={c}): img1={arr1[y,x,c]}, img2={arr2[y,x,c]}, diff={arr2[y,x,c]-arr1[y,x,c]}")
