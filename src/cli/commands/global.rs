use comfy_table::{Table, presets};

use crate::cli;
use crate::error::Result;
use crate::store::queries;

/// Run the `global` command: list all projects with save counts.
pub fn run() -> Result<()> {
    let conn = cli::require_store()?;
    let projects = queries::list_projects(&conn)?;

    if projects.is_empty() {
        println!("No projects found.");
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(presets::NOTHING);
    table.set_header(vec!["Project", "Saves", "Last Save"]);

    for project in &projects {
        table.add_row(vec![
            &project.project_path,
            &project.save_count.to_string(),
            &project.last_save,
        ]);
    }

    println!("{table}");

    Ok(())
}
