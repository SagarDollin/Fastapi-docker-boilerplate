FROM python:3.9

# Set the working directory
WORKDIR /src

# Copy only the requirements file to the container
COPY ./requirements.txt /src/requirements.txt

# Install the dependencies
RUN pip install --no-cache-dir --upgrade -r /src/requirements.txt
