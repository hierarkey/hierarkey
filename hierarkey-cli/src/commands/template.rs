// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{Parser, Subcommand};

pub mod render;

#[derive(Subcommand)]
pub enum TemplateCommand {
    /// Render a template file by substituting {{ /namespace:path }} placeholders with secret values
    Render(TemplateRenderArgs),
}

#[derive(Parser, Debug)]
#[command(after_long_help = r#"Usage examples:

    # Render a template to stdout
    hkey template render --file template.env

    # Render a template to a file
    hkey template render --file template.env --output .env

Template syntax:
    Use {{ /namespace:path }} anywhere in the template file to reference a secret.
    Whitespace inside the braces is ignored. Examples:
        DATABASE_URL={{ /prod:db/url }}
        API_KEY={{/prod:api/key}}
    "#)]
pub struct TemplateRenderArgs {
    /// Template file to render
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: String,

    /// Output file (defaults to stdout if omitted)
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<String>,
}
