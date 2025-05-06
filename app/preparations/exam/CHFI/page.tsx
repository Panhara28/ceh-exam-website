import ExamInterface from "@/components/exam-interface";
import { CHFI_DUMP_QUESTIONS } from "@/data/chfi";
import { Metadata } from "next";

export default function PreparationExameCHFIPage() {
  return (
    <>
      <main className="min-h-screen p-4 md:p-8 bg-gray-50 dark:bg-gray-900">
        <div className="max-w-5xl mx-auto">
          <h1 className="text-3xl md:text-4xl font-bold text-center mb-8 text-gray-800 dark:text-gray-100">
            Ethical Hacker Certification Exam Practice
          </h1>
          <ExamInterface dataQuestions={CHFI_DUMP_QUESTIONS} />
        </div>
      </main>
    </>
  );
}

export const metadata: Metadata = {
  title: "CHFI Pre-Exam | Learn. Secure. Protect.",
  description:
    "your trusted cybersecurity learning platform in Cambodia. We empower individuals and organizations with practical knowledge, training, and tools to defend against digital threats. Explore hands-on tutorials, up-to-date cybersecurity news, and expert guidance to stay secure in an ever-evolving digital world.",
};
