namespace DomainInspectorGUI
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.inputBox = new System.Windows.Forms.TextBox();
            this.analyzeButton = new System.Windows.Forms.Button();
            this.exportButton = new System.Windows.Forms.Button();
            this.resultBox = new System.Windows.Forms.RichTextBox();
            this.SuspendLayout();

            // inputBox
            this.inputBox.Font = new System.Drawing.Font("Segoe UI", 12F);
            this.inputBox.Location = new System.Drawing.Point(12, 12);
            this.inputBox.Size = new System.Drawing.Size(420, 34);

            // analyzeButton
            this.analyzeButton.Font = new System.Drawing.Font("Segoe UI", 12F);
            this.analyzeButton.Location = new System.Drawing.Point(440, 12);
            this.analyzeButton.Size = new System.Drawing.Size(120, 34);
            this.analyzeButton.Text = "Analyze";
            this.analyzeButton.Click += new System.EventHandler(this.analyzeButton_Click);

            // exportButton
            this.exportButton.Font = new System.Drawing.Font("Segoe UI", 12F);
            this.exportButton.Location = new System.Drawing.Point(570, 12);
            this.exportButton.Size = new System.Drawing.Size(140, 34);
            this.exportButton.Text = "Export JSON";
            this.exportButton.Click += new System.EventHandler(this.exportButton_Click);

            // resultBox
            this.resultBox.Font = new System.Drawing.Font("Consolas", 11F);
            this.resultBox.Location = new System.Drawing.Point(12, 60);
            this.resultBox.Size = new System.Drawing.Size(698, 450);
            this.resultBox.BackColor = System.Drawing.Color.Black;
            this.resultBox.ForeColor = System.Drawing.Color.White;

            // Form1
            this.ClientSize = new System.Drawing.Size(720, 520);
            this.Controls.Add(this.inputBox);
            this.Controls.Add(this.analyzeButton);
            this.Controls.Add(this.exportButton);
            this.Controls.Add(this.resultBox);
            this.Text = "Domain & IP Investigation Tool";
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        private System.Windows.Forms.TextBox inputBox;
        private System.Windows.Forms.Button analyzeButton;
        private System.Windows.Forms.Button exportButton;
        private System.Windows.Forms.RichTextBox resultBox;
    }
}
