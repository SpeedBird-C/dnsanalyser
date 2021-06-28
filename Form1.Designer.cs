namespace AnalyzerDNS
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.pcapFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.buttonBrowse = new System.Windows.Forms.Button();
            this.labelFile = new System.Windows.Forms.Label();
            this.textBoxFile = new System.Windows.Forms.TextBox();
            this.textBoxInsecure = new System.Windows.Forms.TextBox();
            this.labelInsecure = new System.Windows.Forms.Label();
            this.buttonAnalyze = new System.Windows.Forms.Button();
            this.textBoxSuspects = new System.Windows.Forms.TextBox();
            this.labelSuspects = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // buttonBrowse
            // 
            this.buttonBrowse.Location = new System.Drawing.Point(610, 16);
            this.buttonBrowse.Margin = new System.Windows.Forms.Padding(1);
            this.buttonBrowse.Name = "buttonBrowse";
            this.buttonBrowse.Size = new System.Drawing.Size(70, 24);
            this.buttonBrowse.TabIndex = 0;
            this.buttonBrowse.Text = "Browse...";
            this.buttonBrowse.UseVisualStyleBackColor = true;
            this.buttonBrowse.Click += new System.EventHandler(this.buttonBrowse_Click);
            // 
            // labelFile
            // 
            this.labelFile.AutoSize = true;
            this.labelFile.Location = new System.Drawing.Point(4, 4);
            this.labelFile.Margin = new System.Windows.Forms.Padding(1, 0, 1, 0);
            this.labelFile.Name = "labelFile";
            this.labelFile.Size = new System.Drawing.Size(26, 13);
            this.labelFile.TabIndex = 1;
            this.labelFile.Text = "File:";
            // 
            // textBoxFile
            // 
            this.textBoxFile.Location = new System.Drawing.Point(4, 18);
            this.textBoxFile.Margin = new System.Windows.Forms.Padding(1);
            this.textBoxFile.Name = "textBoxFile";
            this.textBoxFile.ReadOnly = true;
            this.textBoxFile.Size = new System.Drawing.Size(606, 20);
            this.textBoxFile.TabIndex = 2;
            // 
            // textBoxInsecure
            // 
            this.textBoxInsecure.Location = new System.Drawing.Point(85, 67);
            this.textBoxInsecure.Margin = new System.Windows.Forms.Padding(1);
            this.textBoxInsecure.Multiline = true;
            this.textBoxInsecure.Name = "textBoxInsecure";
            this.textBoxInsecure.ReadOnly = true;
            this.textBoxInsecure.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.textBoxInsecure.Size = new System.Drawing.Size(160, 360);
            this.textBoxInsecure.TabIndex = 7;
            // 
            // labelInsecure
            // 
            this.labelInsecure.AutoSize = true;
            this.labelInsecure.Location = new System.Drawing.Point(130, 53);
            this.labelInsecure.Margin = new System.Windows.Forms.Padding(1, 0, 1, 0);
            this.labelInsecure.Name = "labelInsecure";
            this.labelInsecure.Size = new System.Drawing.Size(37, 13);
            this.labelInsecure.TabIndex = 15;
            this.labelInsecure.Text = "Hosts:";
            // 
            // buttonAnalyze
            // 
            this.buttonAnalyze.Enabled = false;
            this.buttonAnalyze.Location = new System.Drawing.Point(282, 228);
            this.buttonAnalyze.Margin = new System.Windows.Forms.Padding(1);
            this.buttonAnalyze.Name = "buttonAnalyze";
            this.buttonAnalyze.Size = new System.Drawing.Size(70, 24);
            this.buttonAnalyze.TabIndex = 17;
            this.buttonAnalyze.Text = "Analyze";
            this.buttonAnalyze.UseVisualStyleBackColor = true;
            this.buttonAnalyze.Click += new System.EventHandler(this.buttonAnalyze_Click);
            // 
            // textBoxSuspects
            // 
            this.textBoxSuspects.Location = new System.Drawing.Point(356, 68);
            this.textBoxSuspects.Margin = new System.Windows.Forms.Padding(1);
            this.textBoxSuspects.Multiline = true;
            this.textBoxSuspects.Name = "textBoxSuspects";
            this.textBoxSuspects.ReadOnly = true;
            this.textBoxSuspects.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textBoxSuspects.Size = new System.Drawing.Size(323, 359);
            this.textBoxSuspects.TabIndex = 18;
            // 
            // labelSuspects
            // 
            this.labelSuspects.AutoSize = true;
            this.labelSuspects.Location = new System.Drawing.Point(356, 53);
            this.labelSuspects.Margin = new System.Windows.Forms.Padding(1, 0, 1, 0);
            this.labelSuspects.Name = "labelSuspects";
            this.labelSuspects.Size = new System.Drawing.Size(54, 13);
            this.labelSuspects.TabIndex = 19;
            this.labelSuspects.Text = "Suspects:";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(683, 431);
            this.Controls.Add(this.labelSuspects);
            this.Controls.Add(this.textBoxSuspects);
            this.Controls.Add(this.buttonAnalyze);
            this.Controls.Add(this.labelInsecure);
            this.Controls.Add(this.textBoxInsecure);
            this.Controls.Add(this.textBoxFile);
            this.Controls.Add(this.labelFile);
            this.Controls.Add(this.buttonBrowse);
            this.Margin = new System.Windows.Forms.Padding(1);
            this.Name = "Form1";
            this.Text = "AnalyzerDNS";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.OpenFileDialog pcapFileDialog;
        private System.Windows.Forms.Button buttonBrowse;
        private System.Windows.Forms.Label labelFile;
        private System.Windows.Forms.TextBox textBoxFile;
        private System.Windows.Forms.TextBox textBoxInsecure;
        private System.Windows.Forms.Label labelInsecure;
        private System.Windows.Forms.Button buttonAnalyze;
        private System.Windows.Forms.TextBox textBoxSuspects;
        private System.Windows.Forms.Label labelSuspects;
    }
}

