# OS Identification
gradlew = "./gradlew"
expected_ref = "$EXPECTED_REF"
if os.name == "nt":
  gradlew = "gradlew.bat"
  expected_ref = "%EXPECTED_REF%"

# Build
custom_build(
    # Name of the container image
    ref = 'edge-service',
    # Command to build the container image
    command = gradlew + ' bootBuildImage --imageName ' + expected_ref,

    # Files to watch that trigger a new build
    deps=['build.gradle', './build/classes'],
    live_update=[
      sync('./build/classes/java/main', '/workspace/BOOT-INF/classes')
    ]
)

# Deploy
k8s_yaml(kustomize('k8s'))

# Manage
k8s_resource('edge-service', port_forwards=['9000:9000'])
