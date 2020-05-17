<template>
	<div>
		<b-card
			overlay
			:title="section.header"
			:img-src="section.src"
			:img-alt="section.header"
			class="section-header"
		>
			<b-card-text>
				{{ !section.lead ? section.description : section.lead }}
			</b-card-text>
			<b-button
				v-if="assignmentMode"
				class="btn-primary"
				@click="filterAssignments"
			>
				Takaisin
			</b-button>
			<b-button v-else class="btn-primary" @click="filterAssignments">
				Tehtävät
			</b-button>
		</b-card>
		<b-container fluid>
			<component
				v-for="item in items"
				:key="item.order"
				:is="item.type"
				:id="item.contentId"
			/>
		</b-container>
	</div>
</template>

<style scoped>
.section-header {
	margin-bottom: 3rem;
	background-color: var(--color-main);
	color: #ffffff;
}
</style>

<script>
import { mapGetters } from 'vuex'
// components are only imported when needed
const Assignment = () => import('~/components/Assignment.vue')
const MultipleChoice = () => import('~/components/MultipleChoice.vue')
const SpecialText = () => import('~/components/SpecialText.vue')
const TheoryElement = () => import('~/components/TheoryElement.vue')
const ReturnAssignment = () => import('~/components/ReturnAssignment.vue')
const VideoEmbed = () => import('~/components/VideoEmbed.vue')
export default {
	components: {
		Assignment,
		MultipleChoice,
		SpecialText,
		TheoryElement,
		ReturnAssignment,
		VideoEmbed
	},
	data() {
		return {
			items: [],
			assignmentMode: false,
			assignmentsData: {
				type: 'assignments',
				lvl: 'section',
				id: parseInt(this.$route.params.id)
			}
		}
	},
	computed: {
		...mapGetters({
			sectionById: 'sections/sectionById',
			sectionStructure: 'structure/sectionStructure',
			getContentList: 'structure/getContentList'
		}),
		sectionId() {
			return parseInt(this.$route.params.id)
		},
		section() {
			return this.sectionById(this.sectionId)
		}
	},
	methods: {
		filterAssignments() {
			this.assignmentMode = !this.assignmentMode
			if (this.assignmentMode === true) {
				this.items = this.getContentList(this.assignmentsData)
			} else {
				this.items = this.sectionStructure(this.sectionId)
			}
		}
	},
	beforeMount() {
		this.items = this.sectionStructure(this.sectionId)
	}
}
</script>
