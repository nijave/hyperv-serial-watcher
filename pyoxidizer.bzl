def make_exe():
    dist = default_python_distribution()
    policy = dist.make_python_packaging_policy()
    python_config = dist.make_python_interpreter_config()

    python_config.run_module = "main"

    exe = dist.to_python_executable(
        name="hyperv-serial-watcher",
        packaging_policy=policy,
        config=python_config,
    )

    for resource in exe.pip_install(["-r", "requirements.txt"]):
        resource.add_location = "in-memory"
        exe.add_python_resource(resource)

    exe.add_python_resources(exe.read_package_root(
        path=".",
        packages=["main"],
    ))

    return exe

def make_embedded_resources(exe):
    return exe.to_embedded_resources()

def make_install(exe):
    files = FileManifest()
    files.add_python_resource(".", exe)
    return files

register_target("exe", make_exe)
register_target("resources", make_embedded_resources, depends=["exe"], default_build_script=True)
register_target("install", make_install, depends=["exe"], default=True)

resolve_targets()
