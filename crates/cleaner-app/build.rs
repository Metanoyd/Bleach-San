fn main() {
    if !cfg!(target_os = "windows") {
        return;
    }
    let mut resources = winres::WindowsResource::new();
    resources.set_icon("icon.ico");
    resources.set_manifest(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges>
      <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
    </requestedPrivileges></security>
  </trustInfo>
</assembly>"#,
    );
    resources
        .compile()
        .expect("compile Windows icon and manifest");
}
