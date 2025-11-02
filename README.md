Precisamos criar manualmente o ICD NVIDIA:

Crie a pasta de vendors, se não existir:

sudo mkdir -p /etc/OpenCL/vendors

Crie o arquivo nvidia.icd:

echo "libnvidia-opencl.so.1" | sudo tee /etc/OpenCL/vendors/nvidia.icd

Atualize o cache (opcional):

sudo ldconfig

clinfo
