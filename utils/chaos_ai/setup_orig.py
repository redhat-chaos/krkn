import setuptools
# from setuptools_cythonize import get_cmdclass

setuptools.setup(
    # cmdclass=get_cmdclass(),
    name="aichaos",
    version="0.0.1",
    author="Sandeep Hans",
    author_email="shans001@in.ibm.com",
    description="Chaos AI",
    long_description="Chaos Engineering using AI",
    long_description_content_type="text/markdown",
    url="",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.9',
    #install_requires=['numpy==1.18.1','pandas==0.25.3',
    #'scikit-learn==0.22.1',
    #'datetime','scipy==1.4.1',
    #'tqdm==4.47.0','requests==2.23.0',
    #'flasgger==0.9.4','Flask==1.1.2']
)