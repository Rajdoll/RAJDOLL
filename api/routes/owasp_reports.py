"""
OWASP Report API Routes
Generate and download OWASP WSTG v4.2 compliant reports
"""

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import os
import psycopg2
from multi_agent_system.utils.owasp_report_generator import generate_owasp_report


router = APIRouter()


class ReportGenerationRequest(BaseModel):
    """Request model for report generation"""
    job_id: int
    format: str = "markdown"  # markdown, json, pdf, html, all


class ReportGenerationResponse(BaseModel):
    """Response model for report generation"""
    success: bool
    message: str
    files: dict


def get_db_connection():
    """Get PostgreSQL database connection"""
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "db"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        database=os.getenv("POSTGRES_DB", "rajdoll"),
        user=os.getenv("POSTGRES_USER", "rajdoll"),
        password=os.getenv("POSTGRES_PASSWORD", "rajdoll")
    )


@router.post("/reports/owasp/generate", response_model=ReportGenerationResponse)
async def generate_owasp_wstg_report(request: ReportGenerationRequest):
    """
    Generate OWASP WSTG v4.2 compliant security report
    
    Supports multiple formats:
    - markdown: Markdown file (.md)
    - json: JSON file (.json)
    - pdf: PDF file (requires Pandoc) or HTML fallback
    - html: HTML file (.html)
    - all: Generate all formats
    """
    try:
        # Connect to database
        conn = get_db_connection()
        
        # Generate reports
        output_dir = "reports"
        os.makedirs(output_dir, exist_ok=True)
        
        report_files = generate_owasp_report(conn, request.job_id, output_dir)
        
        conn.close()
        
        # Filter by requested format
        if request.format != "all":
            if request.format not in report_files:
                raise HTTPException(
                    status_code=400,
                    detail=f"Format '{request.format}' not available. Available: {list(report_files.keys())}"
                )
            report_files = {request.format: report_files[request.format]}
        
        return ReportGenerationResponse(
            success=True,
            message=f"OWASP WSTG report generated successfully for Job #{request.job_id}",
            files=report_files
        )
    
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.get("/reports/owasp/download/{job_id}/{format}")
async def download_owasp_report(job_id: int, format: str = "markdown"):
    """
    Download OWASP WSTG report in specified format
    
    Formats: markdown, json, pdf, html
    """
    try:
        # Generate report first
        conn = get_db_connection()
        output_dir = "reports"
        report_files = generate_owasp_report(conn, job_id, output_dir)
        conn.close()
        
        # Get file path
        if format == "pdf":
            # Check if actual PDF exists, otherwise use HTML
            file_path = report_files.get("pdf")
            if not file_path or not file_path.endswith(".pdf"):
                file_path = report_files.get("pdf")  # This might be HTML
                format = "html"
        else:
            file_path = report_files.get(format)
        
        if not file_path or not os.path.exists(file_path):
            raise HTTPException(
                status_code=404,
                detail=f"Report format '{format}' not found for Job #{job_id}"
            )
        
        # Determine media type
        media_types = {
            "markdown": "text/markdown",
            "json": "application/json",
            "pdf": "application/pdf",
            "html": "text/html",
        }
        
        media_type = media_types.get(format, "application/octet-stream")
        
        # Return file
        filename = os.path.basename(file_path)
        
        return FileResponse(
            path=file_path,
            media_type=media_type,
            filename=filename,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")


@router.get("/reports/owasp/preview/{job_id}")
async def preview_owasp_report(job_id: int):
    """
    Preview OWASP WSTG report as HTML (inline, not download)
    """
    try:
        conn = get_db_connection()
        output_dir = "reports"
        report_files = generate_owasp_report(conn, job_id, output_dir)
        conn.close()
        
        # Read Markdown file
        md_path = report_files.get("markdown")
        if not md_path or not os.path.exists(md_path):
            raise HTTPException(status_code=404, detail=f"Report not found for Job #{job_id}")
        
        with open(md_path, "r", encoding="utf-8") as f:
            md_content = f.read()
        
        # Simple conversion to HTML (or use markdown library)
        from multi_agent_system.utils.owasp_report_generator import OWASPReportGenerator
        generator = OWASPReportGenerator(None)
        html_content = generator._markdown_to_html(md_content)
        
        return Response(content=html_content, media_type="text/html")
    
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Preview failed: {str(e)}")


@router.get("/reports/owasp/list")
async def list_generated_reports():
    """
    List all generated OWASP reports
    """
    try:
        output_dir = "reports"
        if not os.path.exists(output_dir):
            return {"reports": []}
        
        files = os.listdir(output_dir)
        
        # Group by job_id
        reports = {}
        for file in files:
            if file.startswith("OWASP_WSTG_Report_Job"):
                parts = file.split("_")
                job_id = parts[3].replace("Job", "")
                
                if job_id not in reports:
                    reports[job_id] = {
                        "job_id": job_id,
                        "files": []
                    }
                
                reports[job_id]["files"].append({
                    "filename": file,
                    "format": file.split(".")[-1],
                    "size": os.path.getsize(os.path.join(output_dir, file)),
                })
        
        return {"reports": list(reports.values())}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list reports: {str(e)}")
