# Use official Python image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variable to indicate Docker environment
ENV DOCKER_CONTAINER=1

# Copy requirements file if exists
COPY requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose port (change if your app uses a different port)
EXPOSE 8501

# Set default command (change main.py to your entrypoint)
CMD ["bash"]